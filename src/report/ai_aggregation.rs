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

    /// Extract a field value from JSON response (deprecated, kept for compatibility)
    #[allow(dead_code)]
    fn extract_json_field(_json: &str, _field: &str) -> Option<String> {
        None
    }

    /// Semantic deduplication: uses LLM to identify and merge duplicate findings
    #[allow(dead_code)]
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
    fn group_findings_by_location<'a>(
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
    fn detect_conflicts(
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
    fn apply_consensus_algorithms(
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
    fn calculate_ai_confidence(&self, consensus: &ConsensusResult) -> AiConfidenceScore {
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::findings::Severity;
    use crate::llm::LlmConfig;

    fn make_config() -> LlmConfig {
        LlmConfig {
            base_url: "http://test".to_string(),
            api_key: "test-key".to_string(),
            model: "test-model".to_string(),
            models: vec!["test-model".to_string()],
            timeout: 30,
            max_retries: 3,
            retry_backoff_ms: 1000,
        }
    }

    fn make_finding(
        id: &str,
        severity: Severity,
        confidence: f32,
        file: &str,
        line: Option<u32>,
        cwe: Option<&str>,
        verification: Option<VerificationStatus>,
    ) -> VulnerabilityFinding {
        VulnerabilityFinding {
            id: id.to_string(),
            title: format!("Finding {}", id),
            description: "Test description".to_string(),
            severity,
            confidence_score: confidence,
            cwe_id: cwe.map(String::from),
            file_path: file.to_string(),
            line_number: line,
            code_snippet: Some("test code".to_string()),
            diff_hunk: None,
            recommendation: Some("Fix this".to_string()),
            code_location: None,
            already_reported: false,
            sources: vec!["test".to_string()],
            commit_reference: None,
            ticket_reference: None,
            priority_score: None,
            cross_file_references: None,
            verification_status: verification,
            verification_notes: None,
            verification_error: None,
            agent_evidence_path: None,
            security_issue: None,
            poc_code: None,
            mitigation_code: None,
            poc_format: None,
            llm_model: None,
            agent_mode: false,
        }
    }

    #[test]
    fn test_ai_aggregation_new() {
        let config = make_config();
        let _phase = AiAggregationPhase::new(config);
    }

    #[tokio::test]
    async fn test_run_aggregation() {
        let config = make_config();
        let phase = AiAggregationPhase::new(config);
        let context = AnalysisContext::default();

        let findings = vec![
            make_finding(
                "f1",
                Severity::Critical,
                0.9,
                "src/main.rs",
                Some(42),
                Some("CWE-79"),
                Some(VerificationStatus::Confirmed),
            ),
            make_finding(
                "f2",
                Severity::High,
                0.8,
                "src/lib.rs",
                Some(100),
                Some("CWE-89"),
                None,
            ),
        ];

        let result = phase.run(findings, &context).await;

        assert_eq!(result.unified_reports.len(), 2);
        assert!(!result.executive_summary.is_empty());
    }

    #[test]
    fn test_conflict_detection_severity() {
        let config = make_config();
        let phase = AiAggregationPhase::new(config);

        let findings = vec![
            make_finding(
                "f1",
                Severity::Critical,
                0.9,
                "src/main.rs",
                Some(42),
                Some("CWE-79"),
                None,
            ),
            make_finding(
                "f2",
                Severity::Low,
                0.8,
                "src/main.rs",
                Some(42),
                Some("CWE-79"),
                None,
            ),
        ];

        let grouped = phase.group_findings_by_location(&findings);
        let conflicts = phase.detect_conflicts(&grouped);

        assert!(!conflicts.is_empty());
        assert_eq!(conflicts[0].conflict_type, ConflictType::SeverityMismatch);
    }

    #[test]
    fn test_consensus_algorithms() {
        let config = make_config();
        let phase = AiAggregationPhase::new(config);

        let findings = vec![
            make_finding(
                "f1",
                Severity::Critical,
                0.9,
                "src/main.rs",
                Some(42),
                Some("CWE-79"),
                Some(VerificationStatus::Confirmed),
            ),
            make_finding(
                "f2",
                Severity::Critical,
                0.3,
                "src/main.rs",
                Some(42),
                Some("CWE-79"),
                Some(VerificationStatus::FalsePositive),
            ),
        ];

        let conflicts = Vec::new();
        let consensus_results = phase.apply_consensus_algorithms(&findings, &conflicts);

        assert_eq!(consensus_results.len(), 2);
    }

    #[test]
    fn test_ai_confidence_calculation() {
        let config = make_config();
        let phase = AiAggregationPhase::new(config);

        let finding = make_finding(
            "f1",
            Severity::Critical,
            0.9,
            "src/main.rs",
            Some(42),
            Some("CWE-79"),
            Some(VerificationStatus::Confirmed),
        );

        let consensus = ConsensusResult {
            finding: finding.clone(),
            agreement_count: 2,
            total_sources: 2,
            consensus_score: 0.8,
            confirming_sources: vec![FindingSource::LlmDiscovery, FindingSource::LlmVerification],
            contradicting_sources: vec![],
            likely_false_positive: false,
            recommendation: ConsensusRecommendation::IncludeHighConfidence,
        };

        let ai_confidence = phase.calculate_ai_confidence(&consensus);

        assert!(ai_confidence.overall > 0.0);
        assert!(!ai_confidence.positive_factors.is_empty());
    }

    #[tokio::test]
    async fn test_empty_findings() {
        let config = make_config();
        let phase = AiAggregationPhase::new(config);
        let context = AnalysisContext::default();

        let findings: Vec<VulnerabilityFinding> = vec![];
        let result = phase.run(findings, &context).await;

        assert_eq!(result.unified_reports.len(), 0);
        assert!(result
            .executive_summary
            .contains("Total Unique Findings: 0"));
    }

    #[tokio::test]
    async fn test_false_positive_detection() {
        let config = make_config();
        let phase = AiAggregationPhase::new(config);
        let context = AnalysisContext::default();

        let findings = vec![make_finding(
            "f1",
            Severity::Medium,
            0.4,
            "src/main.rs",
            Some(42),
            Some("CWE-79"),
            Some(VerificationStatus::FalsePositive),
        )];

        let result = phase.run(findings, &context).await;

        assert!(result.statistics.false_positives_detected > 0);
    }

    #[tokio::test]
    async fn test_update_context() {
        let config = make_config();
        let phase = AiAggregationPhase::new(config);
        let mut context = AnalysisContext::default();

        let findings = vec![make_finding(
            "f1",
            Severity::Critical,
            0.9,
            "src/main.rs",
            Some(42),
            Some("CWE-79"),
            Some(VerificationStatus::Confirmed),
        )];

        let result = phase.run(findings, &context).await;
        phase.update_context(&result, &mut context);

        assert!(!context.findings_so_far.is_empty());
    }

    #[test]
    fn test_group_findings_by_location() {
        let config = make_config();
        let phase = AiAggregationPhase::new(config);

        let findings = vec![
            make_finding(
                "f1",
                Severity::High,
                0.8,
                "src/main.rs",
                Some(42),
                Some("CWE-79"),
                None,
            ),
            make_finding(
                "f2",
                Severity::High,
                0.9,
                "src/main.rs",
                Some(42),
                Some("CWE-79"),
                None,
            ),
            make_finding(
                "f3",
                Severity::Critical,
                0.95,
                "src/lib.rs",
                Some(100),
                Some("CWE-89"),
                None,
            ),
        ];

        let grouped = phase.group_findings_by_location(&findings);

        assert_eq!(grouped.get("src/main.rs:42").unwrap().len(), 2);
        assert_eq!(grouped.get("src/lib.rs:100").unwrap().len(), 1);
    }

    #[tokio::test]
    async fn test_async_compatible() {
        // Verify the struct works with async contexts
        let config = make_config();
        let _phase = AiAggregationPhase::new(config);
        // Basic smoke test - struct creation succeeds
    }

    #[tokio::test]
    async fn test_enriched_findings_never_have_empty_description() {
        // Create a finding with empty description
        let finding = VulnerabilityFinding {
            id: "test-001".to_string(),
            title: "Test Vulnerability".to_string(),
            description: String::new(), // Empty description
            severity: Severity::Medium,
            confidence_score: 0.8,
            cwe_id: Some("CWE-79".to_string()),
            file_path: "/tmp/test.c".to_string(),
            line_number: Some(42),
            code_snippet: None,
            diff_hunk: None,
            recommendation: None,
            code_location: None,
            already_reported: false,
            sources: vec![],
            commit_reference: None,
            ticket_reference: None,
            priority_score: None,
            cross_file_references: None,
            verification_status: None,
            verification_notes: None,
            verification_error: None,
            agent_evidence_path: None,
            security_issue: None,
            agent_mode: false,
            llm_model: None,
            mitigation_code: None,
            poc_code: None,
            poc_format: None,
        };

        // Create aggregation phase with mock LLM (will fail, triggering fallback)
        let config = make_config();
        let phase = AiAggregationPhase::new(config);

        // Enrich the finding
        let (enriched, _llm_failed) = phase.enrich_findings_with_llm(&[finding.clone()]).await;

        // Assert: description must NOT be empty after enrichment
        assert!(!enriched.is_empty(), "Should have enriched findings");
        assert!(
            !enriched[0].description.is_empty(),
            "Enriched finding must have non-empty description. Got: '{}'",
            enriched[0].description
        );
        assert!(
            enriched[0].recommendation.is_some(),
            "Enriched finding must have recommendation"
        );
    }

    #[tokio::test]
    async fn test_aggregation_phase_calls_enrich_findings() {
        // This test verifies that the AiAggregationPhase actually enriches findings
        // when LLM is unavailable, falling back to generated descriptions
        let finding = VulnerabilityFinding {
            id: "test-002".to_string(),
            title: "Buffer Overflow".to_string(),
            description: String::new(), // Empty - should be filled by fallback
            severity: Severity::High,
            confidence_score: 0.9,
            cwe_id: Some("CWE-120".to_string()),
            file_path: "/tmp/vuln.c".to_string(),
            line_number: Some(42),
            code_snippet: None,
            diff_hunk: None,
            recommendation: None,
            code_location: None,
            already_reported: false,
            sources: vec!["semgrep".to_string()],
            commit_reference: None,
            ticket_reference: None,
            priority_score: None,
            cross_file_references: None,
            verification_status: None,
            verification_notes: None,
            verification_error: None,
            agent_evidence_path: None,
            security_issue: None,
            agent_mode: false,
            llm_model: None,
            mitigation_code: None,
            poc_code: None,
            poc_format: None,
        };

        // Create aggregation phase with invalid LLM config (will fail, triggering fallback)
        let config = LlmConfig {
            base_url: "http://invalid.invalid".to_string(),
            api_key: "fake_key".to_string(),
            model: String::new(),
            models: vec![],
            timeout: 1, // Very short timeout to fail fast
            max_retries: 1,
            retry_backoff_ms: 0,
        };
        let phase = AiAggregationPhase::new(config);

        // Enrich findings - LLM will fail, fallback should trigger
        let (enriched, llm_failed) = phase.enrich_findings_with_llm(&[finding.clone()]).await;

        // Assert: LLM should have failed
        assert!(llm_failed, "LLM should have failed with invalid endpoint");

        // Assert: description should still be populated via fallback
        assert!(!enriched.is_empty(), "Should have findings");
        assert!(
            !enriched[0].description.is_empty(),
            "Fallback description must be populated even when LLM fails. Got empty string"
        );
        assert!(
            enriched[0].description.contains("Buffer Overflow")
                || enriched[0].description.contains("vulnerability"),
            "Fallback description should contain meaningful content"
        );
    }
}
