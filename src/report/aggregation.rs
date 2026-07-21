//! Report Aggregation Phase
//!
//! Aggregates findings from all previous analysis phases:
//! - Deduplicates findings by location and type
//! - Calculates aggregate statistics
//! - Generates executive summary
//! - Creates prioritized finding list
//! - Integrates with AnalysisContext (T5)

use crate::analysis_context::AnalysisContext;
use crate::findings::{Severity, VerificationStatus, VulnerabilityFinding};
use crate::root_cause_dedup::GlobalFpStore;

/// Aggregated statistics from all findings.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, Default)]
pub struct AggregateStatistics {
    /// Total unique findings count.
    pub total_findings: usize,
    /// Findings by severity level.
    pub critical_count: usize,
    pub high_count: usize,
    pub medium_count: usize,
    pub low_count: usize,
    pub info_count: usize,
    /// Average confidence score across all findings.
    pub average_confidence: f32,
    /// Count of verified findings.
    pub verified_count: usize,
    /// Count of false positives.
    pub false_positive_count: usize,
    /// Count of findings needing review.
    pub needs_review_count: usize,
    /// Count of unique files affected.
    pub unique_files_affected: usize,
    /// Count of findings with cross-file references.
    pub cross_file_findings: usize,
    /// Findings by category (CWE or custom).
    pub findings_by_category: std::collections::HashMap<String, usize>,
}

/// Executive summary of the analysis.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ExecutiveSummary {
    /// Overall risk level assessment.
    pub risk_level: String,
    /// Summary of findings distribution.
    pub findings_summary: String,
    /// Key recommendations.
    pub recommendations: Vec<String>,
    /// Files requiring immediate attention.
    pub priority_files: Vec<String>,
    /// Total findings count.
    pub total_findings: usize,
}

/// A prioritized finding with rank and priority score.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct PrioritizedFinding {
    /// The vulnerability finding.
    pub finding: VulnerabilityFinding,
    /// Priority rank (1 = highest priority).
    pub rank: usize,
    /// Priority score (0.0 - 1.0).
    pub priority_score: f32,
    /// Reason for priority ranking.
    pub priority_reason: String,
}

/// Result of the aggregation phase.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct AggregationResult {
    /// Aggregated statistics.
    pub statistics: AggregateStatistics,
    /// Executive summary.
    pub summary: ExecutiveSummary,
    /// Prioritized findings list.
    pub prioritized_findings: Vec<PrioritizedFinding>,
    /// All unique findings after deduplication.
    pub unique_findings: Vec<VulnerabilityFinding>,
}

/// Report aggregation phase - combines and analyzes findings from all phases.
#[derive(Debug)]
pub struct ReportAggregationPhase;

impl ReportAggregationPhase {
    /// Create a new ReportAggregationPhase.
    pub fn new() -> Self {
        Self
    }

    /// Aggregate findings from all previous phases.
    ///
    /// # Arguments
    /// * `findings` - All findings from previous phases
    /// * `context` - AnalysisContext containing previous phase outputs
    /// * `fp_store` - Optional false positive store to filter out known FPs
    ///
    /// # Returns
    /// `AggregationResult` with statistics, summary, and prioritized findings
    pub fn run(
        &self,
        findings: Vec<VulnerabilityFinding>,
        _context: &AnalysisContext,
        fp_store: Option<&GlobalFpStore>,
    ) -> AggregationResult {
        // Step 1: Deduplicate findings by location and type
        let unique_findings = self.deduplicate_findings(findings, fp_store);

        // Step 2: Calculate aggregate statistics
        let statistics = self.calculate_statistics(&unique_findings);

        // Step 3: Generate executive summary
        let summary = self.generate_executive_summary(&statistics, &unique_findings, _context);

        // Step 4: Create prioritized finding list
        let prioritized_findings = self.prioritize_findings(&unique_findings);

        AggregationResult {
            statistics,
            summary,
            prioritized_findings,
            unique_findings,
        }
    }

    /// Deduplicate findings by file path, line number, and CWE ID.
    ///
    /// # Arguments
    /// * `findings` - All findings to deduplicate
    /// * `fp_store` - Optional false positive store to filter out known FPs
    pub fn deduplicate_findings(
        &self,
        findings: Vec<VulnerabilityFinding>,
        fp_store: Option<&GlobalFpStore>,
    ) -> Vec<VulnerabilityFinding> {
        use std::collections::HashSet;

        let mut seen = HashSet::new();
        let mut unique = Vec::new();

        for finding in findings {
            // Filter out false positives if FP store is provided
            if let Some(store) = fp_store {
                // Use the finding's id to check against FP store
                // Note: In practice, you might want to compute a root cause ID here
                // For now, we check the finding's id directly
                if store.is_false_positive(&finding.id) {
                    continue;
                }
            }

            let key = format!(
                "{}:{}:{}",
                finding.file_path,
                finding
                    .line_number
                    .map(|l| l.to_string())
                    .unwrap_or_default(),
                finding.cwe_id.clone().unwrap_or_else(|| finding.id.clone())
            );

            if !seen.contains(&key) {
                seen.insert(key);
                unique.push(finding);
            }
        }

        unique
    }

    /// Calculate aggregate statistics from findings.
    pub fn calculate_statistics(&self, findings: &[VulnerabilityFinding]) -> AggregateStatistics {
        let mut stats = AggregateStatistics {
            total_findings: findings.len(),
            ..Default::default()
        };

        // Count by severity
        for finding in findings {
            match finding.severity {
                Severity::Critical => stats.critical_count += 1,
                Severity::High => stats.high_count += 1,
                Severity::Medium => stats.medium_count += 1,
                Severity::Low => stats.low_count += 1,
                Severity::Info => stats.info_count += 1,
            }

            // Count by verification status
            match finding.verification_status {
                Some(VerificationStatus::Confirmed) => stats.verified_count += 1,
                Some(VerificationStatus::FalsePositive) => stats.false_positive_count += 1,
                Some(VerificationStatus::NeedsReview) => stats.needs_review_count += 1,
                _ => {}
            }

            // Track categories
            let category = finding
                .cwe_id
                .clone()
                .or_else(|| {
                    finding
                        .security_issue
                        .as_ref()
                        .map(|s| format!("{:?}", s.category))
                })
                .unwrap_or_else(|| "unknown".to_string());
            *stats.findings_by_category.entry(category).or_insert(0) += 1;
        }

        // Calculate average confidence
        if !findings.is_empty() {
            stats.average_confidence =
                findings.iter().map(|f| f.confidence_score).sum::<f32>() / findings.len() as f32;
        }

        // Count unique files
        let unique_files: std::collections::HashSet<_> =
            findings.iter().map(|f| f.file_path.clone()).collect();
        stats.unique_files_affected = unique_files.len();

        // Count cross-file findings
        stats.cross_file_findings = findings
            .iter()
            .filter(|f| f.cross_file_references.is_some())
            .count();

        stats
    }

    /// Generate executive summary based on statistics and findings.
    pub fn generate_executive_summary(
        &self,
        stats: &AggregateStatistics,
        findings: &[VulnerabilityFinding],
        _context: &AnalysisContext,
    ) -> ExecutiveSummary {
        let risk_level = if stats.critical_count > 0 {
            "CRITICAL"
        } else if stats.high_count > 0 {
            "HIGH"
        } else if stats.medium_count > 0 {
            "MODERATE"
        } else if stats.low_count > 0 {
            "LOW"
        } else {
            "MINIMAL"
        };

        let findings_summary = format!(
            "Analysis identified {} unique findings across {} files. \
             Distribution: {} Critical, {} High, {} Medium, {} Low, {} Info. \
             Average confidence: {:.1}%.",
            stats.total_findings,
            stats.unique_files_affected,
            stats.critical_count,
            stats.high_count,
            stats.medium_count,
            stats.low_count,
            stats.info_count,
            stats.average_confidence * 100.0
        );

        // Generate recommendations based on findings
        let mut recommendations = Vec::new();

        if stats.critical_count > 0 {
            recommendations.push(format!(
                "URGENT: Address {} critical severity vulnerabilities immediately.",
                stats.critical_count
            ));
        }

        if stats.high_count > 0 {
            recommendations.push(format!(
                "High priority: Review and remediate {} high severity findings.",
                stats.high_count
            ));
        }

        if stats.cross_file_findings > 0 {
            recommendations.push(format!(
                "Note: {} findings involve cross-file reachability - analyze impact thoroughly.",
                stats.cross_file_findings
            ));
        }

        if stats.average_confidence < 0.5 {
            recommendations.push(
                "Low confidence in some findings - manual verification recommended.".to_string(),
            );
        }

        // Get priority files (files with critical/high findings)
        let mut file_severity: std::collections::HashMap<String, usize> =
            std::collections::HashMap::new();
        for finding in findings {
            let severity_weight = match finding.severity {
                Severity::Critical => 10,
                Severity::High => 5,
                Severity::Medium => 2,
                Severity::Low => 1,
                Severity::Info => 0,
            };
            *file_severity.entry(finding.file_path.clone()).or_insert(0) += severity_weight;
        }

        let mut priority_files: Vec<_> = file_severity.into_iter().collect();
        priority_files.sort_by_key(|b| std::cmp::Reverse(b.1));
        let priority_files: Vec<String> = priority_files
            .into_iter()
            .take(5)
            .map(|(file, _)| file)
            .collect();

        ExecutiveSummary {
            risk_level: risk_level.to_string(),
            findings_summary,
            recommendations,
            priority_files,
            total_findings: stats.total_findings,
        }
    }

    /// Prioritize findings based on severity, confidence, and other factors.
    pub fn prioritize_findings(
        &self,
        findings: &[VulnerabilityFinding],
    ) -> Vec<PrioritizedFinding> {
        let mut scored: Vec<(usize, f32, String)> = findings
            .iter()
            .enumerate()
            .map(|(idx, f)| {
                // Calculate priority score
                let severity_score = match f.severity {
                    Severity::Critical => 1.0,
                    Severity::High => 0.8,
                    Severity::Medium => 0.5,
                    Severity::Low => 0.25,
                    Severity::Info => 0.1,
                };

                let confidence_factor = f.confidence_score;

                // Cross-file findings get a boost (wider attack surface)
                let reachability_boost = if f.cross_file_references.is_some() {
                    0.1
                } else {
                    0.0
                };

                // Already reported findings get a slight reduction (assumed known)
                let known_issue_reduction = if f.already_reported { -0.05 } else { 0.0 };

                let priority_score = (severity_score * confidence_factor
                    + reachability_boost
                    + known_issue_reduction)
                    .clamp(0.0, 1.0);

                // Generate priority reason
                let reason = match f.severity {
                    Severity::Critical => "Critical severity vulnerability".to_string(),
                    Severity::High => "High severity issue".to_string(),
                    Severity::Medium => "Medium severity finding".to_string(),
                    Severity::Low => "Low severity issue".to_string(),
                    Severity::Info => "Informational finding".to_string(),
                };

                (idx, priority_score, reason)
            })
            .collect();

        // Sort by priority score descending
        scored.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));

        // Build prioritized finding list
        scored
            .into_iter()
            .enumerate()
            .map(|(rank, (idx, score, reason))| PrioritizedFinding {
                finding: findings[idx].clone(),
                rank: rank + 1,
                priority_score: score,
                priority_reason: reason,
            })
            .collect()
    }

    /// Update AnalysisContext with aggregation results.
    pub fn update_context(&self, result: &AggregationResult, context: &mut AnalysisContext) {
        // Update findings_so_far with aggregated findings
        context.findings_so_far = result
            .unique_findings
            .iter()
            .map(|f| {
                format!(
                    "{}: {} in {} ({})",
                    f.cwe_id.as_deref().unwrap_or("N/A"),
                    f.title,
                    f.file_path,
                    f.severity
                )
            })
            .collect();
    }
}

impl Default for ReportAggregationPhase {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(test)]
    use crate::findings::{Severity, VerificationStatus, VulnerabilityFinding};

    fn create_finding_with_params(
        id: &str,
        title: &str,
        severity: Severity,
    ) -> VulnerabilityFinding {
        VulnerabilityFinding {
            id: id.to_string(),
            title: title.to_string(),
            description: "Test finding".to_string(),
            severity,
            confidence_score: 0.8,
            cwe_id: Some("CWE-79".to_string()),
            file_path: "src/test.rs".to_string(),
            line_number: Some(10),
            code_snippet: Some("test code".to_string()),
            diff_hunk: None,
            recommendation: Some("Fix this".to_string()),
            code_location: None,
            already_reported: false,
            sources: Vec::new(),
            commit_reference: None,
            ticket_reference: None,
            priority_score: None,
            cross_file_references: None,
            verification_status: Some(VerificationStatus::NeedsReview),
            verification_notes: None,
            verification_error: None,
            agent_evidence_path: None,
            agent_mode: false,
            llm_model: None,
            security_issue: None,
            poc_code: None,
            mitigation_code: None,
            poc_format: None,
            statement_range: None,
        }
    }

    // Wrapper for backward compatibility with existing test code
    fn make_finding(id: &str, title: &str, severity: Severity) -> VulnerabilityFinding {
        create_finding_with_params(id, title, severity)
    }

    #[test]
    fn test_deduplicate_findings() {
        let phase = ReportAggregationPhase::new();

        let finding1 = make_finding("f1", "Test finding", Severity::High);
        let finding2 = make_finding("f2", "Test finding", Severity::High);
        let finding3 = make_finding("f3", "Test finding", Severity::Critical);

        let findings = vec![finding1, finding2, finding3];
        let unique = phase.deduplicate_findings(findings, None);

        // All findings have same file, line, and CWE, so they should all be deduplicated to 1
        assert_eq!(unique.len(), 1);
    }

    #[test]
    fn test_calculate_statistics() {
        let phase = ReportAggregationPhase::new();

        let findings = vec![
            make_finding("f1", "Test finding", Severity::Critical),
            make_finding("f2", "Test finding", Severity::High),
            make_finding("f3", "Test finding", Severity::Medium),
        ];

        let stats = phase.calculate_statistics(&findings);

        assert_eq!(stats.total_findings, 3);
        assert_eq!(stats.critical_count, 1);
        assert_eq!(stats.high_count, 1);
        assert_eq!(stats.medium_count, 1);
        // All findings are in the same file (src/test.rs)
        assert_eq!(stats.unique_files_affected, 1);
        assert!((stats.average_confidence - 0.8).abs() < 0.01);
    }

    #[test]
    fn test_prioritize_findings() {
        let phase = ReportAggregationPhase::new();

        let findings = vec![
            make_finding("f1", "Test finding", Severity::Low),
            make_finding("f2", "Test finding", Severity::Critical),
            make_finding("f3", "Test finding", Severity::High),
        ];

        let prioritized = phase.prioritize_findings(&findings);

        assert_eq!(prioritized.len(), 3);
        assert_eq!(prioritized[0].rank, 1);
        // Critical should be first
        assert_eq!(prioritized[0].finding.severity, Severity::Critical);
    }

    #[test]
    fn test_run_aggregation() {
        let phase = ReportAggregationPhase::new();
        let context = AnalysisContext::default();

        let findings = vec![
            make_finding("f1", "Test finding", Severity::Critical),
            make_finding("f2", "Test finding", Severity::High),
        ];

        let result = phase.run(findings, &context, None);

        // Both findings have same file/line/CWE, so deduplicated to 1
        assert_eq!(result.statistics.total_findings, 1);
        assert_eq!(result.statistics.critical_count, 1);
        assert_eq!(result.statistics.high_count, 0); // High was deduplicated
        assert_eq!(result.summary.risk_level, "CRITICAL");
        assert_eq!(result.prioritized_findings.len(), 1);
        assert_eq!(result.prioritized_findings[0].rank, 1);
    }

    #[test]
    fn test_executive_summary_generation() {
        let phase = ReportAggregationPhase::new();

        let stats = AggregateStatistics {
            total_findings: 5,
            critical_count: 1,
            high_count: 2,
            medium_count: 1,
            low_count: 1,
            info_count: 0,
            average_confidence: 0.75,
            verified_count: 2,
            false_positive_count: 1,
            needs_review_count: 2,
            unique_files_affected: 3,
            cross_file_findings: 1,
            findings_by_category: std::collections::HashMap::new(),
        };

        let findings = vec![make_finding("f1", "Test finding", Severity::Critical)];

        let context = AnalysisContext::default();
        let summary = phase.generate_executive_summary(&stats, &findings, &context);

        assert_eq!(summary.risk_level, "CRITICAL");
        assert!(!summary.recommendations.is_empty());
        assert!(summary.total_findings > 0);
    }

    #[test]
    fn test_update_context() {
        let phase = ReportAggregationPhase::new();
        let mut context = AnalysisContext::default();

        let finding = make_finding("f1", "Test finding", Severity::Critical);
        let result = AggregationResult {
            statistics: AggregateStatistics {
                total_findings: 1,
                ..Default::default()
            },
            summary: ExecutiveSummary {
                risk_level: "CRITICAL".to_string(),
                findings_summary: "Test".to_string(),
                recommendations: vec![],
                priority_files: vec![],
                total_findings: 1,
            },
            prioritized_findings: vec![],
            unique_findings: vec![finding],
        };

        phase.update_context(&result, &mut context);

        assert!(!context.findings_so_far.is_empty());
    }

    #[test]
    fn test_risk_level_classification() {
        let phase = ReportAggregationPhase::new();

        // Critical risk
        let stats = AggregateStatistics {
            critical_count: 1,
            ..Default::default()
        };
        let summary = phase.generate_executive_summary(&stats, &[], &AnalysisContext::default());
        assert_eq!(summary.risk_level, "CRITICAL");

        // High risk (no critical)
        let stats = AggregateStatistics {
            critical_count: 0,
            high_count: 1,
            ..Default::default()
        };
        let summary = phase.generate_executive_summary(&stats, &[], &AnalysisContext::default());
        assert_eq!(summary.risk_level, "HIGH");

        // Moderate risk (no critical/high)
        let stats = AggregateStatistics {
            critical_count: 0,
            high_count: 0,
            medium_count: 1,
            ..Default::default()
        };
        let summary = phase.generate_executive_summary(&stats, &[], &AnalysisContext::default());
        assert_eq!(summary.risk_level, "MODERATE");
    }
}
