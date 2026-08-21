//! AI Aggregation Phase
//!
//! Aggregates findings from multiple LLM phases, resolves conflicts,
//! generates unified finding reports, applies consensus algorithms for
//! false positive reduction, creates AI confidence scores, and integrates
//! with AnalysisContext.

pub mod conflict_resolver;
pub mod deduplication;
pub mod enrichment;
pub mod models;

use crate::analysis_context::AnalysisContext;
use crate::findings::{VerificationStatus, VulnerabilityFinding};
use crate::llm::LlmConfig;

pub use models::*;

use std::collections::HashMap;

/// AI Aggregation Phase - combines and resolves findings from multiple LLM phases
pub struct AiAggregationPhase {
    config: LlmConfig,
    enrichment: enrichment::EnrichmentService,
}

/// Backward-compatible AI Aggregation (used by scanner.rs)
pub struct AiAggregation {
    config: LlmConfig,
}

impl AiAggregation {
    pub fn new(config: LlmConfig) -> Self {
        Self { config }
    }

    pub async fn generate_executive_summary(
        &self,
        findings: &[VulnerabilityFinding],
    ) -> Result<String, String> {
        if findings.is_empty() {
            return Ok("No vulnerabilities found.".to_string());
        }

        let phase = AiAggregationPhase::new(self.config.clone());
        let context = AnalysisContext::default();
        let result = phase.run(findings.to_vec(), &context).await;

        Ok(result.executive_summary)
    }

    pub async fn generate_risk_assessment(
        &self,
        findings: &[VulnerabilityFinding],
    ) -> Result<String, String> {
        let avg_confidence = if !findings.is_empty() {
            findings.iter().map(|f| f.confidence_score).sum::<f32>() / findings.len() as f32
        } else {
            0.0
        };

        Ok(format!(
            "RISK ASSESSMENT\n\
             ================\n\
             Average Confidence Score: {:.2}\n\
             Findings with Cross-file Reachability: {}\n\
             Already Reported in Ticket System: {}",
            avg_confidence,
            findings
                .iter()
                .filter(|f| f.cross_file_references.is_some())
                .count(),
            findings.iter().filter(|f| f.already_reported).count()
        ))
    }
}

impl AiAggregationPhase {
    /// Create a new AiAggregationPhase
    pub fn new(config: LlmConfig) -> Self {
        let enrichment = enrichment::EnrichmentService::new(&config);
        Self { config, enrichment }
    }

    /// Enrich findings with LLM-generated description and recommendation
    pub async fn enrich_findings_with_llm(
        &self,
        findings: &[VulnerabilityFinding],
    ) -> (Vec<VulnerabilityFinding>, bool) {
        self.enrichment.enrich_findings(findings).await
    }

    /// Semantic deduplication: uses LLM to identify and merge duplicate findings
    async fn semantic_deduplication(
        &self,
        findings: &[VulnerabilityFinding],
    ) -> Vec<VulnerabilityFinding> {
        use super::ai_aggregation::deduplication::DeduplicationService;

        let dedup_service = DeduplicationService::new(&self.config);
        dedup_service.deduplicate(findings).await
    }

    /// Run the AI aggregation phase
    pub async fn run(
        &self,
        findings: Vec<VulnerabilityFinding>,
        context: &AnalysisContext,
    ) -> AiAggregationResult {
        // Step 0: Perform semantic deduplication FIRST to avoid enriching duplicates
        let deduplicated_findings =
            if !self.config.api_key.is_empty() && !self.config.base_url.is_empty() {
                self.semantic_deduplication(&findings).await
            } else {
                findings.clone()
            };

        // Step 0.5: Enrich only the unique findings with LLM
        let (enriched_findings, _llm_failed) =
            if !self.config.api_key.is_empty() && !self.config.base_url.is_empty() {
                self.enrich_findings_with_llm(&deduplicated_findings).await
            } else {
                (deduplicated_findings.clone(), false)
            };

        // Step 1: Group findings by location
        let grouped = self.group_findings_by_location(&enriched_findings);

        // Step 2: Detect and resolve conflicts
        let conflicts = self.detect_conflicts(&grouped);

        // Step 3: Apply consensus algorithms
        let consensus_results = self.apply_consensus_algorithms(&enriched_findings, &conflicts);

        // Step 4: Generate unified reports with AI confidence scores
        let unified_reports = self.generate_unified_reports(&enriched_findings, &consensus_results);

        // Step 5: Calculate statistics
        let statistics = self.calculate_statistics(&unified_reports);

        // Step 6: Generate executive summary
        let executive_summary = self.generate_executive_summary(&statistics, context);

        // Step 7: Update context
        let mut ctx = context.clone();
        self.update_context(
            &AiAggregationResult {
                unified_reports: unified_reports.clone(),
                conflicts: conflicts.clone(),
                statistics: statistics.clone(),
                executive_summary: executive_summary.clone(),
                enriched_findings: enriched_findings.to_vec(),
            },
            &mut ctx,
        );

        AiAggregationResult {
            unified_reports,
            conflicts,
            statistics,
            executive_summary,
            enriched_findings: enriched_findings.to_vec(),
        }
    }

    /// Group findings by their location (file + line)
    pub fn group_findings_by_location<'a>(
        &self,
        findings: &'a [VulnerabilityFinding],
    ) -> HashMap<String, Vec<&'a VulnerabilityFinding>> {
        let mut grouped: HashMap<String, Vec<&'a VulnerabilityFinding>> = HashMap::new();

        for finding in findings {
            let key = format!(
                "{}:{}",
                finding.file_path,
                finding
                    .line_number
                    .map(|l| l.to_string())
                    .unwrap_or_default()
            );
            grouped.entry(key).or_default().push(finding);
        }

        grouped
    }

    /// Detect conflicts between findings
    pub fn detect_conflicts(
        &self,
        grouped: &HashMap<String, Vec<&VulnerabilityFinding>>,
    ) -> Vec<FindingConflict> {
        let mut conflicts = Vec::new();

        for (location, findings) in grouped {
            if findings.len() < 2 {
                continue;
            }

            // Check for severity mismatches
            let severities: Vec<_> = findings.iter().map(|f| f.severity).collect();
            if severities
                .iter()
                .collect::<std::collections::HashSet<_>>()
                .len()
                > 1
            {
                let conflict = conflict_resolver::ConflictResolver::resolve_severity_conflict(
                    location, findings,
                );
                conflicts.push(conflict);
                continue;
            }

            // Check for CWE mismatches
            let cwes: Vec<_> = findings.iter().filter_map(|f| f.cwe_id.as_ref()).collect();
            if cwes.iter().collect::<std::collections::HashSet<_>>().len() > 1 {
                let conflict =
                    conflict_resolver::ConflictResolver::resolve_cwe_conflict(location, findings);
                conflicts.push(conflict);
                continue;
            }

            // Check for verification conflicts
            let has_verified = findings
                .iter()
                .any(|f| f.verification_status == Some(VerificationStatus::Confirmed));
            let has_fp = findings
                .iter()
                .any(|f| f.verification_status == Some(VerificationStatus::FalsePositive));

            if has_verified && has_fp {
                let conflict = conflict_resolver::ConflictResolver::resolve_verification_conflict(
                    location, findings,
                );
                conflicts.push(conflict);
                continue;
            }

            // Check for confidence conflicts
            let confidences: Vec<f32> = findings.iter().map(|f| f.confidence_score).collect();
            let min_conf = confidences.iter().cloned().fold(f32::INFINITY, f32::min);
            let max_conf = confidences
                .iter()
                .cloned()
                .fold(f32::NEG_INFINITY, f32::max);

            if max_conf - min_conf > 0.3 {
                let conflict = conflict_resolver::ConflictResolver::resolve_confidence_conflict(
                    location, findings,
                );
                conflicts.push(conflict);
            }
        }

        conflicts
    }

    /// Apply consensus algorithms to detect false positives
    pub fn apply_consensus_algorithms(
        &self,
        findings: &[VulnerabilityFinding],
        _conflicts: &[FindingConflict],
    ) -> Vec<ConsensusResult> {
        let mut results = Vec::new();

        for finding in findings {
            // Count sources that support this finding
            let mut confirming_sources = Vec::new();
            let mut contradicting_sources = Vec::new();

            // If verified as confirmed, it has strong support
            if finding.verification_status == Some(VerificationStatus::Confirmed) {
                confirming_sources.push(FindingSource::LlmVerification);
            }

            // If marked as false positive, it contradicts
            if finding.verification_status == Some(VerificationStatus::FalsePositive) {
                contradicting_sources.push(FindingSource::LlmVerification);
            }

            // If has high confidence, consider it supporting
            if finding.confidence_score >= 0.8 {
                confirming_sources.push(FindingSource::LlmDiscovery);
            }

            // Calculate consensus score
            let total = confirming_sources.len() + contradicting_sources.len();
            let consensus_score = if total == 0 {
                finding.confidence_score
            } else {
                confirming_sources.len() as f32 / total as f32
            };

            // Determine if likely false positive
            let likely_false_positive = finding.verification_status
                == Some(VerificationStatus::FalsePositive)
                || (contradicting_sources.len() > confirming_sources.len()
                    && consensus_score < 0.3);

            // Determine recommendation
            let recommendation = if likely_false_positive {
                ConsensusRecommendation::ExcludeFalsePositive
            } else if consensus_score >= 0.7 {
                ConsensusRecommendation::IncludeHighConfidence
            } else if consensus_score >= 0.4 {
                ConsensusRecommendation::IncludeNeedsReview
            } else {
                ConsensusRecommendation::ManualReview
            };

            results.push(ConsensusResult {
                finding: finding.clone(),
                agreement_count: confirming_sources.len(),
                total_sources: total.max(1),
                consensus_score,
                confirming_sources,
                contradicting_sources,
                likely_false_positive,
                recommendation,
            });
        }

        results
    }

    /// Generate unified finding reports with AI confidence scores
    fn generate_unified_reports(
        &self,
        findings: &[VulnerabilityFinding],
        consensus_results: &[ConsensusResult],
    ) -> Vec<UnifiedFindingReport> {
        consensus_results
            .iter()
            .map(|consensus| {
                let ai_confidence = self.calculate_ai_confidence(consensus);

                UnifiedFindingReport {
                    finding: consensus.finding.clone(),
                    ai_confidence,
                    consensus: consensus.clone(),
                    conflicts_resolved: false,
                    original_findings: findings
                        .iter()
                        .filter(|f| {
                            f.file_path == consensus.finding.file_path
                                && f.line_number == consensus.finding.line_number
                        })
                        .cloned()
                        .collect(),
                }
            })
            .collect()
    }

    /// Calculate AI confidence score breakdown
    pub fn calculate_ai_confidence(&self, consensus: &ConsensusResult) -> AiConfidenceScore {
        let mut positive_factors = Vec::new();
        let mut negative_factors = Vec::new();

        // Semantic analysis confidence (based on sources)
        let semantic = if consensus
            .confirming_sources
            .contains(&FindingSource::LlmDiscovery)
        {
            positive_factors.push("LLM Discovery identified this finding".to_string());
            0.8
        } else if consensus
            .confirming_sources
            .contains(&FindingSource::Semgrep)
        {
            positive_factors.push("Semgrep detected this pattern".to_string());
            0.75
        } else {
            0.5
        };

        // Verification confidence
        let verification = if consensus.finding.verification_status
            == Some(VerificationStatus::Confirmed)
        {
            positive_factors.push("Finding verified by LLM".to_string());
            0.9
        } else if consensus.finding.verification_status == Some(VerificationStatus::FalsePositive) {
            negative_factors.push("Marked as false positive".to_string());
            0.1
        } else {
            0.5
        };

        // Context analysis confidence
        let context = if consensus.finding.cross_file_references.is_some() {
            positive_factors.push("Cross-file reachability confirmed".to_string());
            0.85
        } else {
            0.6
        };

        // Consensus confidence
        let consensus_conf = consensus.consensus_score;

        // Calculate overall confidence
        let overall =
            (semantic * 0.25 + verification * 0.35 + context * 0.15 + consensus_conf * 0.25)
                .clamp(0.0, 1.0);

        // Adjust for negative factors
        if consensus.likely_false_positive {
            negative_factors.push("Consensus suggests false positive".to_string());
        }

        if consensus.finding.confidence_score < 0.5 {
            negative_factors.push("Low base confidence score".to_string());
        }

        AiConfidenceScore {
            overall,
            semantic,
            verification,
            context,
            consensus: consensus_conf,
            positive_factors,
            negative_factors,
        }
    }

    /// Calculate aggregation statistics
    fn calculate_statistics(&self, reports: &[UnifiedFindingReport]) -> AiAggregationStatistics {
        let total = reports.len();
        let false_positives = reports
            .iter()
            .filter(|r| r.consensus.likely_false_positive)
            .count();
        let needs_review = reports
            .iter()
            .filter(|r| r.consensus.recommendation == ConsensusRecommendation::IncludeNeedsReview)
            .count();
        let high_confidence = reports
            .iter()
            .filter(|r| r.ai_confidence.overall >= 0.7)
            .count();
        let avg_confidence = if total > 0 {
            reports.iter().map(|r| r.ai_confidence.overall).sum::<f32>() / total as f32
        } else {
            0.0
        };

        AiAggregationStatistics {
            total_unique_findings: total,
            conflicts_resolved: 0,
            false_positives_detected: false_positives,
            needs_manual_review: needs_review,
            high_confidence_count: high_confidence,
            average_confidence: avg_confidence,
        }
    }

    /// Generate executive summary
    fn generate_executive_summary(
        &self,
        stats: &AiAggregationStatistics,
        _context: &AnalysisContext,
    ) -> String {
        let risk_level = if stats.false_positives_detected > stats.total_unique_findings / 2 {
            "LOW"
        } else if stats.high_confidence_count > stats.total_unique_findings / 2 {
            "CRITICAL"
        } else if stats.average_confidence > 0.7 {
            "HIGH"
        } else {
            "MODERATE"
        };

        format!(
            "AI AGGREGATION SUMMARY\n\
             =====================\n\
             Total Unique Findings: {}\n\
             High Confidence: {}\n\
             False Positives Detected: {}\n\
             Needs Manual Review: {}\n\
             Average AI Confidence: {:.1}%\n\
             \n\
             Risk Level: {}\n\
             \n\
             Key Insights:\n\
             - {} findings resolved through conflict resolution\n\
             - {} high-confidence vulnerabilities require immediate attention\n\
             - {} findings marked as likely false positives\n\
             \n\
             Recommendation: {}\n",
            stats.total_unique_findings,
            stats.high_confidence_count,
            stats.false_positives_detected,
            stats.needs_manual_review,
            stats.average_confidence * 100.0,
            risk_level,
            stats.conflicts_resolved,
            stats.high_confidence_count,
            stats.false_positives_detected,
            match risk_level {
                "CRITICAL" => "Immediate action required on high-confidence findings",
                "HIGH" => "Prioritize remediation of high-confidence vulnerabilities",
                "MODERATE" => "Review needs_manual_review findings",
                _ => "Low risk - continue monitoring",
            }
        )
    }

    /// Update AnalysisContext with aggregation results
    pub fn update_context(&self, result: &AiAggregationResult, context: &mut AnalysisContext) {
        // Update findings_so_far with aggregated findings
        context.findings_so_far = result
            .unified_reports
            .iter()
            .map(|r| {
                format!(
                    "{}: {} in {} (AI confidence: {:.1}%)",
                    r.finding.cwe_id.as_deref().unwrap_or("N/A"),
                    r.finding.title,
                    r.finding.file_path,
                    r.ai_confidence.overall * 100.0
                )
            })
            .collect();
    }
}
